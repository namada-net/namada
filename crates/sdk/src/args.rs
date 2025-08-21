//! Structures encapsulating SDK arguments

use std::borrow::Cow;
use std::fmt::Display;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration as StdDuration;

use either::Either;
use masp_primitives::transaction::components::sapling::builder::BuildParams;
use masp_primitives::zip32::PseudoExtendedKey;
use namada_core::address::{Address, MASP};
use namada_core::chain::{BlockHeight, ChainId, Epoch};
use namada_core::collections::HashMap;
use namada_core::dec::Dec;
use namada_core::ethereum_events::EthAddress;
use namada_core::keccak::KeccakHash;
use namada_core::key::{SchemeType, common};
use namada_core::masp::{DiversifierIndex, MaspEpoch, PaymentAddress};
use namada_core::string_encoding::StringEncoded;
use namada_core::time::DateTimeUtc;
use namada_core::token::Amount;
use namada_core::{storage, token};
use namada_governance::cli::onchain::{
    DefaultProposal, PgfFundingProposal, PgfStewardProposal,
};
use namada_ibc::IbcShieldingData;
use namada_io::{Io, display_line};
use namada_token::masp::utils::RetryStrategy;
use namada_tx::Memo;
use namada_tx::data::GasLimit;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::eth_bridge::bridge_pool;
use crate::ibc::core::host::types::identifiers::{ChannelId, PortId};
use crate::ibc::{NamadaMemo, NamadaMemoData};
use crate::rpc::{
    get_registry_from_xcs_osmosis_contract, osmosis_denom_from_namada_denom,
    query_ibc_denom, query_osmosis_route_and_min_out,
};
use crate::signing::{SigningTxData, gen_disposable_signing_key};
use crate::wallet::{DatedSpendingKey, DatedViewingKey};
use crate::{Namada, rpc, tx};

/// [`Duration`](StdDuration) wrapper that provides a
/// method to parse a value from a string.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(transparent)]
pub struct Duration(pub StdDuration);

impl ::std::str::FromStr for Duration {
    type Err = String;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ::duration_str::parse(s).map(Duration)
    }
}

/// Abstraction of types being used in Namada
pub trait NamadaTypes: Clone + std::fmt::Debug {
    /// Represents an address on the ledger
    type Address: Clone + std::fmt::Debug;
    /// Represents an address that defaults to a native token
    type AddrOrNativeToken: Clone + std::fmt::Debug + From<Self::Address>;
    /// Represents a key pair
    type Keypair: Clone + std::fmt::Debug;
    /// Represents the address of a Tendermint endpoint (used in context-less
    /// CLI commands where chain config isn't available)
    type TendermintAddress: Clone + std::fmt::Debug;
    /// RPC address of a locally configured node
    type ConfigRpcTendermintAddress: Clone
        + std::fmt::Debug
        + From<Self::TendermintAddress>;
    /// Represents the address of an Ethereum endpoint
    type EthereumAddress: Clone + std::fmt::Debug;
    /// Represents a shielded viewing key
    type ViewingKey: Clone + std::fmt::Debug;
    /// Represents a shielded spending key
    type SpendingKey: Clone + std::fmt::Debug;
    /// Represents a shielded viewing key
    type DatedViewingKey: Clone + std::fmt::Debug;
    /// Represents a shielded spending key
    type DatedSpendingKey: Clone + std::fmt::Debug;
    /// Represents a shielded payment address
    type PaymentAddress: Clone + std::fmt::Debug;
    /// Represents the owner of a balance
    type BalanceOwner: Clone + std::fmt::Debug;
    /// Represents a public key
    type PublicKey: Clone + std::fmt::Debug;
    /// Represents the source of a Transfer
    type TransferSource: Clone + std::fmt::Debug;
    /// Represents the target of a Transfer
    type TransferTarget: Clone + std::fmt::Debug;
    /// Represents some data that is used in a transaction
    type Data: Clone + std::fmt::Debug;
    /// Bridge pool recommendations conversion rates table.
    type BpConversionTable: Clone + std::fmt::Debug;
    /// Address of a `namada-masp-indexer` live instance
    type MaspIndexerAddress: Clone + std::fmt::Debug;
    /// Represents a block height
    type BlockHeight: Clone + std::fmt::Debug;
}

/// The concrete types being used in Namada SDK
#[derive(Clone, Debug)]
pub struct SdkTypes;

/// An entry in the Bridge pool recommendations conversion
/// rates table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BpConversionTableEntry {
    /// An alias for the token, or the string representation
    /// of its address if none is available.
    pub alias: String,
    /// Conversion rate from the given token to gwei.
    pub conversion_rate: f64,
}

impl NamadaTypes for SdkTypes {
    type AddrOrNativeToken = Address;
    type Address = Address;
    type BalanceOwner = namada_core::masp::BalanceOwner;
    type BlockHeight = namada_core::chain::BlockHeight;
    type BpConversionTable = HashMap<Address, BpConversionTableEntry>;
    type ConfigRpcTendermintAddress = tendermint_rpc::Url;
    type Data = Vec<u8>;
    type DatedSpendingKey = DatedSpendingKey;
    type DatedViewingKey = DatedViewingKey;
    type EthereumAddress = ();
    type Keypair = namada_core::key::common::SecretKey;
    type MaspIndexerAddress = String;
    type PaymentAddress = namada_core::masp::PaymentAddress;
    type PublicKey = namada_core::key::common::PublicKey;
    type SpendingKey = PseudoExtendedKey;
    type TendermintAddress = tendermint_rpc::Url;
    type TransferSource = namada_core::masp::TransferSource;
    type TransferTarget = namada_core::masp::TransferTarget;
    type ViewingKey = namada_core::masp::ExtendedViewingKey;
}

/// Common query arguments
#[derive(Clone, Debug)]
pub struct Query<C: NamadaTypes = SdkTypes> {
    /// The address of the ledger node as host:port
    pub ledger_address: C::ConfigRpcTendermintAddress,
}

/// Common query arguments
#[derive(Clone, Debug)]
pub struct QueryWithoutCtx<C: NamadaTypes = SdkTypes> {
    /// The address of the ledger node as host:port
    pub ledger_address: C::TendermintAddress,
}

/// Transaction associated results arguments
#[derive(Clone, Debug)]
pub struct QueryResult<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Hash of transaction to lookup
    pub tx_hash: String,
}

/// Custom transaction arguments
#[derive(Clone, Debug)]
pub struct TxCustom<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Path to the tx WASM code file
    pub code_path: Option<PathBuf>,
    /// Path to the data file
    pub data_path: Option<C::Data>,
    /// Path to the serialized transaction
    pub serialized_tx: Option<C::Data>,
    /// The optional address that correspond to the signatures/signing-keys
    pub owner: Option<C::Address>,
    /// List of signatures to attach to the transaction
    pub signatures: Vec<C::Data>,
    /// Optional path to a serialized wrapper signature
    pub wrapper_signature: Option<C::Data>,
}

impl<C: NamadaTypes> TxBuilder<C> for TxCustom<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxCustom {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxCustom<C> {
    /// Path to the tx WASM code file
    pub fn code_path(self, code_path: PathBuf) -> Self {
        Self {
            code_path: Some(code_path),
            ..self
        }
    }

    /// Path to the data file
    pub fn data_path(self, data_path: C::Data) -> Self {
        Self {
            data_path: Some(data_path),
            ..self
        }
    }

    /// Path to the serialized transaction
    pub fn serialized_tx(self, serialized_tx: C::Data) -> Self {
        Self {
            serialized_tx: Some(serialized_tx),
            ..self
        }
    }

    /// The address that correspond to the signatures/signing-keys
    pub fn owner(self, owner: Option<C::Address>) -> Self {
        Self { owner, ..self }
    }
}

impl TxCustom {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, Option<SigningTxData>)> {
        tx::build_custom(context, self).await
    }
}

/// An amount read in by the cli
#[derive(Copy, Clone, Debug)]
pub enum InputAmount {
    /// An amount whose representation has been validated
    /// against the allowed representation in storage
    Validated(token::DenominatedAmount),
    /// The parsed amount read in from the cli. It has
    /// not yet been validated against the allowed
    /// representation in storage.
    Unvalidated(token::DenominatedAmount),
}

impl std::str::FromStr for InputAmount {
    type Err = <token::DenominatedAmount as std::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        token::DenominatedAmount::from_str(s).map(InputAmount::Unvalidated)
    }
}

impl From<token::DenominatedAmount> for InputAmount {
    fn from(amt: token::DenominatedAmount) -> Self {
        InputAmount::Unvalidated(amt)
    }
}

/// Transparent transfer transaction arguments
#[derive(Clone, Debug)]
pub struct TxTransparentTransfer<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// The transfer specific data
    pub sources: Vec<TxTransparentSource<C>>,
    /// The transfer specific data
    pub targets: Vec<TxTransparentTarget<C>>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxTransparentTransfer<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxTransparentTransfer {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxTransparentTransfer<C> {
    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxTransparentTransfer {
    /// Build a transaction from this builder
    pub async fn build(
        &mut self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_transparent_transfer(context, self).await
    }
}

/// Shielded transfer-specific arguments
#[derive(Clone, Debug)]
pub struct TxShieldedSource<C: NamadaTypes = SdkTypes> {
    /// Transfer source spending key
    pub source: C::SpendingKey,
    /// Transferred token address
    pub token: C::Address,
    /// Transferred token amount
    pub amount: InputAmount,
}

/// Shielded transfer-specific arguments
#[derive(Clone, Debug)]
pub struct TxShieldedTarget<C: NamadaTypes = SdkTypes> {
    /// Transfer target address
    pub target: C::PaymentAddress,
    /// Transferred token address
    pub token: C::Address,
    /// Transferred token amount
    pub amount: InputAmount,
}

/// Shielded transfer transaction arguments
#[derive(Clone, Debug)]
pub struct TxShieldedTransfer<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Transfer-specific data
    pub sources: Vec<TxShieldedSource<C>>,
    /// Transfer-specific data
    pub targets: Vec<TxShieldedTarget<C>>,
    /// Optional additional keys for gas payment
    pub gas_spending_key: Option<C::SpendingKey>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxShieldedTransfer<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxShieldedTransfer {
            tx: func(self.tx),
            ..self
        }
    }
}

impl TxShieldedTransfer {
    /// Build a transaction from this builder
    pub async fn build(
        &mut self,
        context: &impl Namada,
        bparams: &mut impl BuildParams,
        skip_fee_handling: bool,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_shielded_transfer(context, self, bparams, skip_fee_handling)
            .await
    }
}

/// Shielding transfer-specific arguments
#[derive(Clone, Debug)]
pub struct TxTransparentSource<C: NamadaTypes = SdkTypes> {
    /// Transfer source spending key
    pub source: C::Address,
    /// Transferred token address
    pub token: C::Address,
    /// Transferred token amount
    pub amount: InputAmount,
}

/// Shielding transfer transaction arguments
#[derive(Clone, Debug)]
pub struct TxShieldingTransfer<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Transfer target data
    pub targets: Vec<TxShieldedTarget<C>>,
    /// Transfer source data
    pub sources: Vec<TxTransparentSource<C>>,
    /// The optional data for the frontend sustainability fee
    pub frontend_sus_fee: Vec<TxTransparentTarget<C>>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxShieldingTransfer<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxShieldingTransfer {
            tx: func(self.tx),
            ..self
        }
    }
}

impl TxShieldingTransfer {
    /// Build a transaction from this builder
    pub async fn build(
        &mut self,
        context: &impl Namada,
        bparams: &mut impl BuildParams,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData, MaspEpoch)> {
        tx::build_shielding_transfer(context, self, bparams).await
    }
}

/// Unshielding transfer-specific arguments
#[derive(Clone, Debug)]
pub struct TxTransparentTarget<C: NamadaTypes = SdkTypes> {
    /// Transfer target address
    pub target: C::Address,
    /// Transferred token address
    pub token: C::Address,
    /// Transferred token amount
    pub amount: InputAmount,
}

/// Unshielding transfer transaction arguments
#[derive(Clone, Debug)]
pub struct TxUnshieldingTransfer<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Transfer source data
    pub sources: Vec<TxShieldedSource<C>>,
    /// Transfer target data (potentially also carries data for the frontend
    /// sustainability fee)
    pub targets: Vec<TxTransparentTarget<C>>,
    /// Optional additional key for gas payment
    pub gas_spending_key: Option<C::SpendingKey>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxUnshieldingTransfer<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxUnshieldingTransfer {
            tx: func(self.tx),
            ..self
        }
    }
}

impl TxUnshieldingTransfer {
    /// Build a transaction from this builder
    pub async fn build(
        &mut self,
        context: &impl Namada,
        bparams: &mut impl BuildParams,
        skip_fee_handling: bool,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_unshielding_transfer(
            context,
            self,
            bparams,
            skip_fee_handling,
        )
        .await
    }
}

/// Individual hop of some route to take through Osmosis pools.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsmosisPoolHop {
    /// The id of the pool to use on Osmosis.
    pub pool_id: String,
    /// The output denomination expected from the
    /// pool on Osmosis.
    pub token_out_denom: String,
}

impl FromStr for OsmosisPoolHop {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split_once(':').map_or_else(
            || {
                Err(format!(
                    "Expected <pool-id>:<output-denom> string, but found \
                     {s:?} instead"
                ))
            },
            |(pool_id, token_out_denom)| {
                Ok(OsmosisPoolHop {
                    pool_id: pool_id.to_owned(),
                    token_out_denom: token_out_denom.to_owned(),
                })
            },
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Constraints on the osmosis swap
pub enum Slippage {
    /// Specifies the minimum amount to be received
    MinOutputAmount(Amount),
    /// A time-weighted average price
    Twap {
        /// The maximum percentage difference allowed between the estimated and
        /// actual trade price. This must be a decimal number in the range
        /// `[0, 100]`.
        slippage_percentage: Dec,
    },
}

/// An token swap on Osmosis
#[derive(Debug, Clone)]
pub struct TxOsmosisSwap<C: NamadaTypes = SdkTypes> {
    /// The IBC transfer data
    pub transfer: TxIbcTransfer<C>,
    /// The token we wish to receive (on Namada)
    pub output_denom: String,
    /// Address of the recipient on Namada
    pub recipient: Either<C::Address, C::PaymentAddress>,
    /// Address to receive funds exceeding the minimum amount,
    /// in case of IBC shieldings
    ///
    /// If unspecified, a disposable address is generated to
    /// receive funds with
    pub overflow: Option<C::Address>,
    ///  Constraints on the  osmosis swap
    pub slippage: Option<Slippage>,
    /// Recovery address (on Osmosis) in case of failure
    pub local_recovery_addr: String,
    /// The route to take through Osmosis pools
    pub route: Option<Vec<OsmosisPoolHop>>,
    /// REST rpc endpoint to the Osmosis GRPC gateway
    pub osmosis_lcd_rpc: Option<String>,
    /// REST rpc endpoint to Osmosis SQS
    pub osmosis_sqs_rpc: Option<String>,
    /// The optional data for the frontend sustainability fee
    /// NOTE: if the swap is shielded (from MASP to MASP), no sustainability
    /// fee should be taken
    // FIXME: try to join this with recipient
    pub frontend_sus_fee: Option<(C::TransferTarget, InputAmount)>,
}

impl TxOsmosisSwap<SdkTypes> {
    /// Create an IBC transfer from the input arguments
    pub async fn into_ibc_transfer<F>(
        self,
        ctx: &impl Namada,
        confirm_swap: F,
    ) -> crate::error::Result<TxIbcTransfer<SdkTypes>>
    where
        F: FnOnce(&[OsmosisPoolHop], &Amount, Option<&Amount>) -> bool,
    {
        #[derive(Serialize)]
        struct Memo {
            wasm: Wasm,
        }

        #[derive(Serialize)]
        struct Wasm {
            contract: String,
            msg: Message,
        }

        #[derive(Serialize)]
        struct Message {
            osmosis_swap: OsmosisSwap,
        }

        #[derive(Serialize)]
        struct OsmosisSwap {
            receiver: String,
            output_denom: String,
            slippage: Slippage,
            on_failed_delivery: LocalRecoveryAddr,
            route: Vec<OsmosisPoolHop>,
            #[serde(skip_serializing_if = "Option::is_none")]
            final_memo: Option<serde_json::Map<String, serde_json::Value>>,
        }

        #[derive(Serialize)]
        struct LocalRecoveryAddr {
            local_recovery_addr: String,
        }

        #[inline]
        fn assert_json_obj(
            value: serde_json::Value,
        ) -> serde_json::Map<String, serde_json::Value> {
            match value {
                serde_json::Value::Object(x) => x,
                _ => unreachable!(),
            }
        }

        const OSMOSIS_SQS_SERVER: &str = "https://sqsprod.osmosis.zone";
        const OSMOSIS_LCD_SERVER: &str = "https://lcd.osmosis.zone";

        let Self {
            mut transfer,
            recipient,
            slippage,
            local_recovery_addr,
            route: fixed_route,
            overflow,
            osmosis_lcd_rpc,
            osmosis_sqs_rpc,
            output_denom: namada_output_denom,
            frontend_sus_fee,
        } = self;

        let osmosis_lcd_rpc = osmosis_lcd_rpc
            .map_or(Cow::Borrowed(OSMOSIS_LCD_SERVER), Cow::Owned);
        let osmosis_sqs_rpc = osmosis_sqs_rpc
            .map_or(Cow::Borrowed(OSMOSIS_SQS_SERVER), Cow::Owned);

        let recipient = recipient.map_either(
            |addr| addr,
            |payment_addr| async move {
                let overflow_receiver = if let Some(overflow) = overflow {
                    overflow
                } else {
                    let addr = (&gen_disposable_signing_key(ctx).await).into();
                    display_line!(
                        ctx.io(),
                        "Sending unshielded funds to disposable address {addr}",
                    );
                    addr
                };
                (payment_addr, overflow_receiver)
            },
        );

        // validate `local_recovery_addr` and the contract addr
        if !bech32::decode(&local_recovery_addr)
            .is_ok_and(|(hrp, data)| hrp.as_str() == "osmo" && data.len() == 20)
        {
            return Err(Error::Other(format!(
                "Invalid Osmosis recovery address {local_recovery_addr:?}"
            )));
        }
        if !bech32::decode(&transfer.receiver)
            .is_ok_and(|(hrp, data)| hrp.as_str() == "osmo" && data.len() == 32)
        {
            return Err(Error::Other(format!(
                "Invalid Osmosis contract address {local_recovery_addr:?}"
            )));
        }

        let registry_xcs_addr = get_registry_from_xcs_osmosis_contract(
            &osmosis_lcd_rpc,
            &transfer.receiver,
        )
        .await?;

        let namada_input_denom =
            query_ibc_denom(ctx, transfer.token.to_string(), None).await;

        let (osmosis_input_denom, _) = osmosis_denom_from_namada_denom(
            &osmosis_lcd_rpc,
            &registry_xcs_addr,
            &namada_input_denom,
        )
        .await?;

        let (osmosis_output_denom, namada_output_addr) =
            osmosis_denom_from_namada_denom(
                &osmosis_lcd_rpc,
                &registry_xcs_addr,
                &namada_output_denom,
            )
            .await?;

        let (route, trade_min_output_amount, quote) =
            query_osmosis_route_and_min_out(
                ctx,
                &transfer.token,
                &osmosis_input_denom,
                transfer.amount,
                &osmosis_output_denom,
                &osmosis_sqs_rpc,
                fixed_route,
                slippage,
            )
            .await?;

        if !confirm_swap(&route, &trade_min_output_amount, quote.as_ref()) {
            return Err(Error::Other("Swap has been cancelled".to_owned()));
        }

        let (receiver, final_memo) = match recipient {
            Either::Left(transparent_recipient) => {
                (transparent_recipient.encode_compat(), None)
            }
            Either::Right(fut) => {
                let (payment_addr, overflow_receiver) = fut.await;

                let amount_to_shield = trade_min_output_amount;
                let shielding_tx = tx::gen_ibc_shielding_transfer(
                    ctx,
                    GenIbcShieldingTransfer {
                        query: Query {
                            ledger_address: transfer.tx.ledger_address.clone(),
                        },
                        output_folder: None,
                        target:
                            namada_core::masp::TransferTarget::PaymentAddress(
                                payment_addr,
                            ),
                        asset: IbcShieldingTransferAsset::Address(
                            namada_output_addr,
                        ),
                        amount: InputAmount::Validated(
                            token::DenominatedAmount::new(
                                amount_to_shield,
                                0u8.into(),
                            ),
                        ),
                        expiration: transfer.tx.expiration.clone(),
                        frontend_sus_fee,
                    },
                )
                .await?
                .ok_or_else(|| {
                    Error::Other(
                        "Failed to generate IBC shielding transfer".to_owned(),
                    )
                })?;

                let memo = assert_json_obj(
                    serde_json::to_value(&NamadaMemo {
                        namada: NamadaMemoData::OsmosisSwap {
                            shielding_data: StringEncoded::new(
                                IbcShieldingData(shielding_tx),
                            ),
                            shielded_amount: amount_to_shield,
                            overflow_receiver,
                        },
                    })
                    .unwrap(),
                );

                (MASP.encode_compat(), Some(memo))
            }
        };

        let cosmwasm_memo = Memo {
            wasm: Wasm {
                contract: transfer.receiver.clone(),
                msg: Message {
                    osmosis_swap: OsmosisSwap {
                        output_denom: osmosis_output_denom,
                        slippage: Slippage::MinOutputAmount(
                            trade_min_output_amount,
                        ),
                        final_memo,
                        receiver,
                        on_failed_delivery: LocalRecoveryAddr {
                            local_recovery_addr,
                        },
                        route,
                    },
                },
            },
        };
        let namada_memo = transfer.ibc_memo.take().map(|memo| {
            assert_json_obj(
                serde_json::to_value(&NamadaMemo {
                    namada: NamadaMemoData::Memo(memo),
                })
                .unwrap(),
            )
        });

        let memo = {
            let mut m = serde_json::to_value(&cosmwasm_memo).unwrap();
            let m_obj = m.as_object_mut().unwrap();

            if let Some(mut namada_memo) = namada_memo {
                m_obj.append(&mut namada_memo);
            }

            m
        };

        transfer.ibc_memo = Some(serde_json::to_string(&memo).unwrap());
        Ok(transfer)
    }
}

/// IBC transfer transaction arguments
#[derive(Clone, Debug)]
pub struct TxIbcTransfer<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Transfer source address
    pub source: C::TransferSource,
    /// Transfer target address
    pub receiver: String,
    /// Transferred token address
    pub token: C::Address,
    /// Transferred token amount
    pub amount: InputAmount,
    /// Port ID
    pub port_id: PortId,
    /// Channel ID
    pub channel_id: ChannelId,
    /// Timeout height of the destination chain
    pub timeout_height: Option<u64>,
    /// Timeout timestamp offset
    pub timeout_sec_offset: Option<u64>,
    /// Refund target address when the shielded transfer failure
    pub refund_target: Option<C::TransferTarget>,
    /// IBC shielding transfer data for the destination chain
    // FIXME: here the shielding transaction to reapply to namada, it should
    // carry the sus fee
    pub ibc_shielding_data: Option<IbcShieldingData>,
    /// Memo for IBC transfer packet
    pub ibc_memo: Option<String>,
    /// Optional additional keys for gas payment
    pub gas_spending_key: Option<C::SpendingKey>,
    /// The optional data for the frontend sustainability fee
    // FIXME: this should probably be an either with ibc_shielding_data. Yes
    // but there would still be the room for errors, maybe need marker traits?
    // Not sure...
    // FIXME: should this be a tuple (receiver, amount) to force the token to
    // be the same as that of the transfer? FIXME: should the frontend fees
    // always be specified just as a percentage and a target address?
    pub frontend_sus_fee: Option<TxTransparentTarget<C>>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxIbcTransfer<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxIbcTransfer {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxIbcTransfer<C> {
    /// Transfer source address
    pub fn source(self, source: C::TransferSource) -> Self {
        Self { source, ..self }
    }

    /// Transfer target address
    pub fn receiver(self, receiver: String) -> Self {
        Self { receiver, ..self }
    }

    /// Transferred token address
    pub fn token(self, token: C::Address) -> Self {
        Self { token, ..self }
    }

    /// Transferred token amount
    pub fn amount(self, amount: InputAmount) -> Self {
        Self { amount, ..self }
    }

    /// Port ID
    pub fn port_id(self, port_id: PortId) -> Self {
        Self { port_id, ..self }
    }

    /// Channel ID
    pub fn channel_id(self, channel_id: ChannelId) -> Self {
        Self { channel_id, ..self }
    }

    /// Timeout height of the destination chain
    pub fn timeout_height(self, timeout_height: u64) -> Self {
        Self {
            timeout_height: Some(timeout_height),
            ..self
        }
    }

    /// Timeout timestamp offset
    pub fn timeout_sec_offset(self, timeout_sec_offset: u64) -> Self {
        Self {
            timeout_sec_offset: Some(timeout_sec_offset),
            ..self
        }
    }

    /// Refund target address
    pub fn refund_target(self, refund_target: C::TransferTarget) -> Self {
        Self {
            refund_target: Some(refund_target),
            ..self
        }
    }

    /// IBC shielding transfer data
    pub fn ibc_shielding_data(self, shielding_data: IbcShieldingData) -> Self {
        Self {
            ibc_shielding_data: Some(shielding_data),
            ..self
        }
    }

    /// Memo for IBC transfer packet
    pub fn ibc_memo(self, ibc_memo: String) -> Self {
        Self {
            ibc_memo: Some(ibc_memo),
            ..self
        }
    }

    /// Gas spending keys
    pub fn gas_spending_keys(self, gas_spending_key: C::SpendingKey) -> Self {
        Self {
            gas_spending_key: Some(gas_spending_key),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxIbcTransfer {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
        bparams: &mut impl BuildParams,
        skip_fee_handling: bool,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData, Option<MaspEpoch>)>
    {
        tx::build_ibc_transfer(context, self, bparams, skip_fee_handling).await
    }
}

/// Transaction to initialize create a new proposal
#[derive(Clone, Debug)]
pub struct InitProposal<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// The proposal data
    pub proposal_data: C::Data,
    /// Flag if proposal is of type Pgf stewards
    pub is_pgf_stewards: bool,
    /// Flag if proposal is of type Pgf funding
    pub is_pgf_funding: bool,
    /// Path to the tx WASM file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for InitProposal<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        InitProposal {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> InitProposal<C> {
    /// The proposal data
    pub fn proposal_data(self, proposal_data: C::Data) -> Self {
        Self {
            proposal_data,
            ..self
        }
    }

    /// Flag if proposal is of type Pgf stewards
    pub fn is_pgf_stewards(self, is_pgf_stewards: bool) -> Self {
        Self {
            is_pgf_stewards,
            ..self
        }
    }

    /// Flag if proposal is of type Pgf funding
    pub fn is_pgf_funding(self, is_pgf_funding: bool) -> Self {
        Self {
            is_pgf_funding,
            ..self
        }
    }

    /// Path to the tx WASM file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl InitProposal {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        let current_epoch = rpc::query_epoch(context.client()).await?;
        let governance_parameters =
            rpc::query_governance_parameters(context.client()).await;

        if self.is_pgf_funding {
            let proposal = PgfFundingProposal::try_from(
                self.proposal_data.as_ref(),
            )
            .map_err(|e| {
                crate::error::TxSubmitError::FailedGovernaneProposalDeserialize(
                    e.to_string(),
                )
            })?
            .validate(&governance_parameters, current_epoch, self.tx.force)
            .map_err(|e| {
                crate::error::TxSubmitError::InvalidProposal(e.to_string())
            })?;

            tx::build_pgf_funding_proposal(context, self, proposal).await
        } else if self.is_pgf_stewards {
            let proposal = PgfStewardProposal::try_from(
                self.proposal_data.as_ref(),
            )
            .map_err(|e| {
                crate::error::TxSubmitError::FailedGovernaneProposalDeserialize(
                    e.to_string(),
                )
            })?;
            let nam_address = context.native_token();
            let author_balance = rpc::get_token_balance(
                context.client(),
                &nam_address,
                &proposal.proposal.author,
                None,
            )
            .await?;
            let proposal = proposal
                .validate(
                    &governance_parameters,
                    current_epoch,
                    author_balance,
                    self.tx.force,
                )
                .map_err(|e| {
                    crate::error::TxSubmitError::InvalidProposal(e.to_string())
                })?;

            tx::build_pgf_stewards_proposal(context, self, proposal).await
        } else {
            let proposal = DefaultProposal::try_from(
                self.proposal_data.as_ref(),
            )
            .map_err(|e| {
                crate::error::TxSubmitError::FailedGovernaneProposalDeserialize(
                    e.to_string(),
                )
            })?;
            let nam_address = context.native_token();
            let author_balance = rpc::get_token_balance(
                context.client(),
                &nam_address,
                &proposal.proposal.author,
                None,
            )
            .await?;
            let proposal = proposal
                .validate(
                    &governance_parameters,
                    current_epoch,
                    author_balance,
                    self.tx.force,
                )
                .map_err(|e| {
                    crate::error::TxSubmitError::InvalidProposal(e.to_string())
                })?;
            tx::build_default_proposal(context, self, proposal).await
        }
    }
}

/// Transaction to vote on a proposal
#[derive(Clone, Debug)]
pub struct VoteProposal<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Proposal id
    pub proposal_id: u64,
    /// The vote
    pub vote: String,
    /// The address of the voter
    pub voter_address: C::Address,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for VoteProposal<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        VoteProposal {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> VoteProposal<C> {
    /// Proposal id
    pub fn proposal_id(self, proposal_id: u64) -> Self {
        Self {
            proposal_id,
            ..self
        }
    }

    /// The vote
    pub fn vote(self, vote: String) -> Self {
        Self { vote, ..self }
    }

    /// The address of the voter
    pub fn voter(self, voter_address: C::Address) -> Self {
        Self {
            voter_address,
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl VoteProposal {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        let current_epoch = rpc::query_epoch(context.client()).await?;
        tx::build_vote_proposal(context, self, current_epoch).await
    }
}

/// Transaction to initialize a new account
#[derive(Clone, Debug)]
pub struct TxInitAccount<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Path to the VP WASM code file for the new account
    pub vp_code_path: PathBuf,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
    /// Public key for the new account
    pub public_keys: Vec<C::PublicKey>,
    /// The account multisignature threshold
    pub threshold: Option<u8>,
}

impl<C: NamadaTypes> TxBuilder<C> for TxInitAccount<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxInitAccount {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxInitAccount<C> {
    /// A vector of public key to associate with the new account
    pub fn public_keys(self, public_keys: Vec<C::PublicKey>) -> Self {
        Self {
            public_keys,
            ..self
        }
    }

    /// A threshold to associate with the new account
    pub fn threshold(self, threshold: u8) -> Self {
        Self {
            threshold: Some(threshold),
            ..self
        }
    }

    /// Path to the VP WASM code file
    pub fn vp_code_path(self, vp_code_path: PathBuf) -> Self {
        Self {
            vp_code_path,
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxInitAccount {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_init_account(context, self).await
    }
}

/// Transaction to initialize a new account
#[derive(Clone, Debug)]
pub struct TxBecomeValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Address of an account that will become a validator.
    pub address: C::Address,
    /// Signature scheme
    pub scheme: SchemeType,
    /// Consensus key
    pub consensus_key: Option<C::PublicKey>,
    /// Ethereum cold key
    pub eth_cold_key: Option<C::PublicKey>,
    /// Ethereum hot key
    pub eth_hot_key: Option<C::PublicKey>,
    /// Protocol key
    pub protocol_key: Option<C::PublicKey>,
    /// Commission rate
    pub commission_rate: Dec,
    /// Maximum commission rate change
    pub max_commission_rate_change: Dec,
    /// The validator email
    pub email: String,
    /// The validator description
    pub description: Option<String>,
    /// The validator website
    pub website: Option<String>,
    /// The validator's discord handle
    pub discord_handle: Option<String>,
    /// The validator's avatar
    pub avatar: Option<String>,
    /// The validator's name
    pub name: Option<String>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
}

impl<C: NamadaTypes> TxBuilder<C> for TxBecomeValidator<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxBecomeValidator {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxBecomeValidator<C> {
    /// Set the address
    pub fn address(self, address: C::Address) -> Self {
        Self { address, ..self }
    }

    /// Set the commission rate
    pub fn commission_rate(self, commission_rate: Dec) -> Self {
        Self {
            commission_rate,
            ..self
        }
    }

    /// Set the max commission rate change
    pub fn max_commission_rate_change(
        self,
        max_commission_rate_change: Dec,
    ) -> Self {
        Self {
            max_commission_rate_change,
            ..self
        }
    }

    /// Set the email
    pub fn email(self, email: String) -> Self {
        Self { email, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxBecomeValidator {
    /// Build the tx
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_become_validator(context, self).await
    }
}

/// Transaction to initialize a new account
#[derive(Clone, Debug)]
pub struct TxInitValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Signature scheme
    pub scheme: SchemeType,
    /// Account keys
    pub account_keys: Vec<C::PublicKey>,
    /// The account multisignature threshold
    pub threshold: Option<u8>,
    /// Consensus key
    pub consensus_key: Option<C::PublicKey>,
    /// Ethereum cold key
    pub eth_cold_key: Option<C::PublicKey>,
    /// Ethereum hot key
    pub eth_hot_key: Option<C::PublicKey>,
    /// Protocol key
    pub protocol_key: Option<C::PublicKey>,
    /// Commission rate
    pub commission_rate: Dec,
    /// Maximum commission rate change
    pub max_commission_rate_change: Dec,
    /// The validator email
    pub email: String,
    /// The validator description
    pub description: Option<String>,
    /// The validator website
    pub website: Option<String>,
    /// The validator's discord handle
    pub discord_handle: Option<String>,
    /// The validator's avatar
    pub avatar: Option<String>,
    /// The validator's name
    pub name: Option<String>,
    /// Path to the VP WASM code file
    pub validator_vp_code_path: PathBuf,
    /// Path to the TX WASM code file
    pub tx_init_account_code_path: PathBuf,
    /// Path to the TX WASM code file
    pub tx_become_validator_code_path: PathBuf,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
}

/// Transaction to update a VP arguments
#[derive(Clone, Debug)]
pub struct TxUpdateAccount<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Path to the VP WASM code file
    pub vp_code_path: Option<PathBuf>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
    /// Address of the account whose VP is to be updated
    pub addr: C::Address,
    /// Public keys
    pub public_keys: Vec<C::PublicKey>,
    /// The account threshold
    pub threshold: Option<u8>,
}

impl<C: NamadaTypes> TxBuilder<C> for TxUpdateAccount<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxUpdateAccount {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxUpdateAccount<C> {
    /// Path to the VP WASM code file
    pub fn vp_code_path(self, vp_code_path: PathBuf) -> Self {
        Self {
            vp_code_path: Some(vp_code_path),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }

    /// Address of the account whose VP is to be updated
    pub fn addr(self, addr: C::Address) -> Self {
        Self { addr, ..self }
    }

    /// Public keys
    pub fn public_keys(self, public_keys: Vec<C::PublicKey>) -> Self {
        Self {
            public_keys,
            ..self
        }
    }

    /// The account threshold
    pub fn threshold(self, threshold: u8) -> Self {
        Self {
            threshold: Some(threshold),
            ..self
        }
    }
}

impl TxUpdateAccount {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_update_account(context, self).await
    }
}

/// Bond arguments
#[derive(Clone, Debug)]
pub struct Bond<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address
    pub validator: C::Address,
    /// Amount of tokens to stake in a bond
    pub amount: token::Amount,
    /// Source address for delegations. For self-bonds, the validator is
    /// also the source.
    pub source: Option<C::Address>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for Bond<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        Bond {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> Bond<C> {
    /// Validator address
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Amount of tokens to stake in a bond
    pub fn amount(self, amount: token::Amount) -> Self {
        Self { amount, ..self }
    }

    /// Source address for delegations. For self-bonds, the validator is
    /// also the source.
    pub fn source(self, source: C::Address) -> Self {
        Self {
            source: Some(source),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl Bond {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_bond(context, self).await
    }
}

/// Unbond arguments
#[derive(Clone, Debug)]
pub struct Unbond<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address
    pub validator: C::Address,
    /// Amount of tokens to unbond from a bond
    pub amount: token::Amount,
    /// Source address for unbonding from delegations. For unbonding from
    /// self-bonds, the validator is also the source
    pub source: Option<C::Address>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl Unbond {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(
        namada_tx::Tx,
        SigningTxData,
        Option<(Epoch, token::Amount)>,
    )> {
        tx::build_unbond(context, self).await
    }
}

impl<C: NamadaTypes> TxBuilder<C> for Unbond<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        Unbond {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> Unbond<C> {
    /// Validator address
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Amount of tokens to unbond from a bond
    pub fn amount(self, amount: token::Amount) -> Self {
        Self { amount, ..self }
    }

    /// Source address for unbonding from delegations. For unbonding from
    /// self-bonds, the validator is also the source
    pub fn source(self, source: C::Address) -> Self {
        Self {
            source: Some(source),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

/// Redelegation arguments
#[derive(Clone, Debug)]
pub struct Redelegate<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Source validator address
    pub src_validator: C::Address,
    /// Destination validator address
    pub dest_validator: C::Address,
    /// Owner of the bonds that are being redelegated
    pub owner: C::Address,
    /// The amount of tokens to redelegate
    pub amount: token::Amount,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl Redelegate {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_redelegation(context, self).await
    }
}

impl<C: NamadaTypes> Redelegate<C> {
    /// Src validator address
    pub fn src_validator(self, src_validator: C::Address) -> Self {
        Self {
            src_validator,
            ..self
        }
    }

    /// Dest validator address
    pub fn dest_validator(self, dest_validator: C::Address) -> Self {
        Self {
            dest_validator,
            ..self
        }
    }

    /// Owner (or delegator or source) of the redelegation
    pub fn owner(self, owner: C::Address) -> Self {
        Self { owner, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl<C: NamadaTypes> TxBuilder<C> for Redelegate<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        Redelegate {
            tx: func(self.tx),
            ..self
        }
    }
}

/// Reveal public key
#[derive(Clone, Debug)]
pub struct RevealPk<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// A public key to be revealed on-chain
    pub public_key: C::PublicKey,
}

impl<C: NamadaTypes> TxBuilder<C> for RevealPk<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        RevealPk {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> RevealPk<C> {
    /// A public key to be revealed on-chain
    pub fn public_key(self, public_key: C::PublicKey) -> Self {
        Self { public_key, ..self }
    }
}

impl RevealPk {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_reveal_pk(context, &self.tx, &self.public_key).await
    }
}

/// Generate shell completions
#[derive(Clone, Debug)]
pub struct Complete {
    /// Which shell
    pub shell: Shell,
}

/// Supported shell types
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub enum Shell {
    Bash,
    Elvish,
    Fish,
    PowerShell,
    Zsh,
    Nushell,
}

impl Display for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.possible_value().get_name().fmt(f)
    }
}

impl FromStr for Shell {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use clap::ValueEnum;

        for variant in Self::value_variants() {
            if variant.possible_value().matches(s, false) {
                return Ok(*variant);
            }
        }
        Err(format!("invalid variant: {s}"))
    }
}

impl Shell {
    fn possible_value(&self) -> clap::builder::PossibleValue {
        use clap::builder::PossibleValue;
        match self {
            Shell::Bash => PossibleValue::new("bash"),
            Shell::Elvish => PossibleValue::new("elvish"),
            Shell::Fish => PossibleValue::new("fish"),
            Shell::PowerShell => PossibleValue::new("powershell"),
            Shell::Zsh => PossibleValue::new("zsh"),
            Shell::Nushell => PossibleValue::new("nushell"),
        }
    }
}

impl clap::ValueEnum for Shell {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Shell::Bash,
            Shell::Elvish,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Zsh,
            Shell::Nushell,
        ]
    }

    fn to_possible_value<'a>(&self) -> Option<clap::builder::PossibleValue> {
        Some(self.possible_value())
    }
}

/// Query proposal votes
#[derive(Clone, Debug)]
pub struct QueryProposalVotes<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Proposal id
    pub proposal_id: u64,
    /// Voter address
    pub voter: Option<C::Address>,
}

/// Query proposal
#[derive(Clone, Debug)]
pub struct QueryProposal<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Proposal id
    pub proposal_id: Option<u64>,
}

/// Query protocol parameters
#[derive(Clone, Debug)]
pub struct QueryProtocolParameters<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
}

/// Query pgf data
#[derive(Clone, Debug)]
pub struct QueryPgf<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
}

/// Withdraw arguments
#[derive(Clone, Debug)]
pub struct Withdraw<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address
    pub validator: C::Address,
    /// Source address for withdrawing from delegations. For withdrawing
    /// from self-bonds, the validator is also the source
    pub source: Option<C::Address>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for Withdraw<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        Withdraw {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> Withdraw<C> {
    /// Validator address
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Source address for withdrawing from delegations. For withdrawing
    /// from self-bonds, the validator is also the source
    pub fn source(self, source: C::Address) -> Self {
        Self {
            source: Some(source),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl Withdraw {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_withdraw(context, self).await
    }
}

/// Claim arguments
#[derive(Clone, Debug)]
pub struct ClaimRewards<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address
    pub validator: C::Address,
    /// Source address for claiming rewards due to bonds. For self-bonds, the
    /// validator is also the source
    pub source: Option<C::Address>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for ClaimRewards<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        ClaimRewards {
            tx: func(self.tx),
            ..self
        }
    }
}

impl ClaimRewards {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_claim_rewards(context, self).await
    }
}

/// Query asset conversions
#[derive(Clone, Debug)]
pub struct QueryConversions<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a token
    pub token: Option<C::Address>,
    /// Epoch of the asset
    pub epoch: Option<MaspEpoch>,
    /// Flag to dump the conversion tree
    pub dump_tree: bool,
}

/// Query token balance(s)
#[derive(Clone, Debug)]
pub struct QueryAccount<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of an owner
    pub owner: C::Address,
}

/// Query token balance(s)
#[derive(Clone, Debug)]
pub struct QueryBalance<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of an owner
    pub owner: C::BalanceOwner,
    /// Address of a token
    pub token: C::Address,
    /// Whether not to convert balances
    pub no_conversions: bool,
    /// Optional height to query balances at
    pub height: Option<C::BlockHeight>,
}

/// Get an estimate for the MASP rewards for the next
/// MASP epoch.
#[derive(Clone, Debug)]
pub struct QueryShieldingRewardsEstimate<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Viewing key
    pub owner: C::ViewingKey,
}

/// Query historical transfer(s)
#[derive(Clone, Debug)]
pub struct QueryTransfers<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of an owner
    pub owner: Option<C::BalanceOwner>,
    /// Address of a token
    pub token: Option<C::Address>,
}

/// Query PoS bond(s)
#[derive(Clone, Debug)]
pub struct QueryBonds<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of an owner
    pub owner: Option<C::Address>,
    /// Address of a validator
    pub validator: Option<C::Address>,
}

/// Query PoS bonded stake
#[derive(Clone, Debug)]
pub struct QueryBondedStake<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: Option<C::Address>,
    /// Epoch in which to find bonded stake
    pub epoch: Option<Epoch>,
}

/// Query the state of a validator (its validator set or if it is jailed)
#[derive(Clone, Debug)]
pub struct QueryValidatorState<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: C::Address,
    /// Epoch in which to find the validator state
    pub epoch: Option<Epoch>,
}

#[derive(Clone, Debug)]
/// Commission rate change args
pub struct CommissionRateChange<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// Value to which the tx changes the commission rate
    pub rate: Dec,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for CommissionRateChange<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        CommissionRateChange {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> CommissionRateChange<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Value to which the tx changes the commission rate
    pub fn rate(self, rate: Dec) -> Self {
        Self { rate, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl CommissionRateChange {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_validator_commission_change(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Consensus key change args
pub struct ConsensusKeyChange<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// New consensus key
    pub consensus_key: Option<C::PublicKey>,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for ConsensusKeyChange<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        ConsensusKeyChange {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> ConsensusKeyChange<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Value to which the tx changes the commission rate
    pub fn consensus_key(self, consensus_key: C::PublicKey) -> Self {
        Self {
            consensus_key: Some(consensus_key),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl ConsensusKeyChange {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_change_consensus_key(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Commission rate change args
pub struct MetaDataChange<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// New validator email
    pub email: Option<String>,
    /// New validator description
    pub description: Option<String>,
    /// New validator website
    pub website: Option<String>,
    /// New validator discord handle
    pub discord_handle: Option<String>,
    /// New validator avatar url
    pub avatar: Option<String>,
    /// New validator name
    pub name: Option<String>,
    /// New validator commission rate
    pub commission_rate: Option<Dec>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for MetaDataChange<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        MetaDataChange {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> MetaDataChange<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }

    /// New validator email
    pub fn email(self, email: String) -> Self {
        Self {
            email: Some(email),
            ..self
        }
    }

    /// New validator description
    pub fn description(self, description: String) -> Self {
        Self {
            description: Some(description),
            ..self
        }
    }

    /// New validator website
    pub fn website(self, website: String) -> Self {
        Self {
            website: Some(website),
            ..self
        }
    }

    /// New validator discord handle
    pub fn discord_handle(self, discord_handle: String) -> Self {
        Self {
            discord_handle: Some(discord_handle),
            ..self
        }
    }

    /// New validator avatar url
    pub fn avatar(self, avatar: String) -> Self {
        Self {
            avatar: Some(avatar),
            ..self
        }
    }

    /// New validator name
    pub fn name(self, name: String) -> Self {
        Self {
            name: Some(name),
            ..self
        }
    }

    /// New validator commission rate
    pub fn commission_rate(self, commission_rate: Dec) -> Self {
        Self {
            commission_rate: Some(commission_rate),
            ..self
        }
    }
}

impl MetaDataChange {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_validator_metadata_change(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Commission rate change args
pub struct UpdateStewardCommission<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Steward address
    pub steward: C::Address,
    /// Value to which the tx changes the commission rate
    pub commission: C::Data,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for UpdateStewardCommission<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        UpdateStewardCommission {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> UpdateStewardCommission<C> {
    /// Steward address
    pub fn steward(self, steward: C::Address) -> Self {
        Self { steward, ..self }
    }

    /// Value to which the tx changes the commission rate
    pub fn commission(self, commission: C::Data) -> Self {
        Self { commission, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl UpdateStewardCommission {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_update_steward_commission(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Commission rate change args
pub struct ResignSteward<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address
    pub steward: C::Address,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for ResignSteward<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        ResignSteward {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> ResignSteward<C> {
    /// Validator address
    pub fn steward(self, steward: C::Address) -> Self {
        Self { steward, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl ResignSteward {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_resign_steward(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Re-activate a jailed validator args
pub struct TxUnjailValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxUnjailValidator<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxUnjailValidator {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxUnjailValidator<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxUnjailValidator {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_unjail_validator(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Deactivate validator args
pub struct TxDeactivateValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxDeactivateValidator<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxDeactivateValidator {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxDeactivateValidator<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxDeactivateValidator {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_deactivate_validator(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Re-activate a deactivated validator args
pub struct TxReactivateValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxReactivateValidator<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxReactivateValidator {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxReactivateValidator<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxReactivateValidator {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        tx::build_reactivate_validator(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Sync notes from MASP owned by the provided spending /
/// viewing keys. Syncing can be told to stop at a given
/// block height.
pub struct ShieldedSync<C: NamadaTypes = SdkTypes> {
    /// The ledger address
    pub ledger_address: C::ConfigRpcTendermintAddress,
    /// Height to sync up to. Defaults to most recent
    pub last_query_height: Option<BlockHeight>,
    /// Spending keys used to determine note ownership
    pub spending_keys: Vec<C::DatedSpendingKey>,
    /// Viewing keys used to determine note ownership
    pub viewing_keys: Vec<C::DatedViewingKey>,
    /// Address of a `namada-masp-indexer` live instance
    ///
    /// If present, the shielded sync will be performed
    /// using data retrieved from the given indexer
    pub with_indexer: Option<C::MaspIndexerAddress>,
    /// Wait for the last query height.
    pub wait_for_last_query_height: bool,
    /// Maximum number of fetch jobs that will ever
    /// execute concurrently during the shielded sync.
    pub max_concurrent_fetches: usize,
    /// Number of blocks fetched per concurrent fetch job.
    pub block_batch_size: usize,
    /// Maximum number of times to retry fetching. If `None`
    /// is provided, defaults to "forever".
    pub retry_strategy: RetryStrategy,
}

/// Query PoS commission rate
#[derive(Clone, Debug)]
pub struct QueryCommissionRate<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: C::Address,
    /// Epoch in which to find commission rate
    pub epoch: Option<Epoch>,
}

/// Query validator metadata
#[derive(Clone, Debug)]
pub struct QueryMetaData<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: C::Address,
}

/// Query PoS slashes
#[derive(Clone, Debug)]
pub struct QuerySlashes<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: Option<C::Address>,
}

/// Query PoS rewards
#[derive(Clone, Debug)]
pub struct QueryRewards<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of the source
    pub source: Option<C::Address>,
    /// Address of the validator
    pub validator: C::Address,
    /// Epoch in which to find rewards
    pub epoch: Option<Epoch>,
}

/// Query PoS delegations
#[derive(Clone, Debug)]
pub struct QueryDelegations<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of an owner
    pub owner: C::Address,
}

/// Query token total supply
#[derive(Clone, Debug)]
pub struct QueryTotalSupply<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Token address
    pub token: C::Address,
}

/// Query effective native supply
#[derive(Clone, Debug)]
pub struct QueryEffNativeSupply<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
}

/// Query estimate of staking rewards rate
#[derive(Clone, Debug)]
pub struct QueryStakingRewardsRate<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
}

/// Query PoS to find a validator
#[derive(Clone, Debug)]
pub struct QueryFindValidator<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Validator address, either Comet or native
    pub addr: Either<String, C::Address>,
}

/// Query the raw bytes of given storage key
#[derive(Clone, Debug)]
pub struct QueryRawBytes<C: NamadaTypes = SdkTypes> {
    /// The storage key to query
    pub storage_key: storage::Key,
    /// Common query args
    pub query: Query<C>,
}

/// Query the IBC rate limit for the specified token
#[derive(Clone, Debug)]
pub struct QueryIbcRateLimit<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Token address
    pub token: C::Address,
}

/// The possible values for the tx expiration
#[derive(Clone, Debug, Default)]
pub enum TxExpiration {
    /// Force the tx to have no expiration
    NoExpiration,
    /// Request the default expiration
    #[default]
    Default,
    /// User-provided custom expiration
    Custom(DateTimeUtc),
}

impl TxExpiration {
    /// Converts the expiration argument into an optional [`DateTimeUtc`]
    pub fn to_datetime(&self) -> Option<DateTimeUtc> {
        match self {
            TxExpiration::NoExpiration => None,
            // Default to 1 hour
            TxExpiration::Default =>
            {
                #[allow(clippy::disallowed_methods)]
                Some(DateTimeUtc::now() + namada_core::time::Duration::hours(1))
            }
            TxExpiration::Custom(exp) => Some(exp.to_owned()),
        }
    }
}

/// Common transaction arguments
#[derive(Clone, Debug)]
pub struct Tx<C: NamadaTypes = SdkTypes> {
    /// Simulate applying the transaction
    pub dry_run: bool,
    /// Simulate applying both the wrapper and inner transactions
    pub dry_run_wrapper: bool,
    /// Dump the raw transaction bytes to file
    pub dump_tx: bool,
    /// Dump the wrapper transaction bytes to file
    pub dump_wrapper_tx: bool,
    /// The output directory path to where serialize the data
    pub output_folder: Option<PathBuf>,
    /// Submit the transaction even if it doesn't pass client checks
    pub force: bool,
    /// Do not wait for the transaction to be added to the blockchain
    pub broadcast_only: bool,
    /// The address of the ledger node as host:port
    pub ledger_address: C::ConfigRpcTendermintAddress,
    /// If any new account is initialized by the tx, use the given alias to
    /// save it in the wallet.
    pub initialized_account_alias: Option<String>,
    /// Whether to force overwrite the above alias, if it is provided, in the
    /// wallet.
    pub wallet_alias_force: bool,
    /// The amount being paid (for gas unit) to include the transaction
    pub fee_amount: Option<InputAmount>,
    /// The fee payer signing key
    pub wrapper_fee_payer: Option<C::PublicKey>,
    /// The token in which the fee is being paid
    pub fee_token: C::AddrOrNativeToken,
    /// The max amount of gas used to process tx
    pub gas_limit: GasLimit,
    /// The optional expiration of the transaction
    pub expiration: TxExpiration,
    /// The chain id for which the transaction is intended
    pub chain_id: Option<ChainId>,
    /// Sign the tx with the key for the given alias from your wallet
    pub signing_keys: Vec<C::PublicKey>,
    /// Path to the TX WASM code file to reveal PK
    pub tx_reveal_code_path: PathBuf,
    /// Password to decrypt key
    pub password: Option<Zeroizing<String>>,
    /// Optional memo to be included in the transaction
    pub memo: Option<Memo>,
    /// Use device to sign the transaction
    pub use_device: bool,
    /// Hardware Wallet transport - HID (USB) or TCP
    pub device_transport: DeviceTransport,
}

/// Hardware Wallet transport - HID (USB) or TCP
#[derive(Debug, Clone, Copy, Default)]
pub enum DeviceTransport {
    /// HID transport (USB connected hardware wallet)
    #[default]
    Hid,
    /// TCP transport
    Tcp,
}

impl FromStr for DeviceTransport {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hid" => Ok(Self::Hid),
            "tcp" => Ok(Self::Tcp),
            raw => Err(format!(
                "Unexpected device transport \"{raw}\". Valid options are \
                 \"hid\" or \"tcp\"."
            )),
        }
    }
}

/// Builder functions for Tx
pub trait TxBuilder<C: NamadaTypes>: Sized {
    /// Apply the given function to the Tx inside self
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>;
    /// Simulate applying the transaction
    fn dry_run(self, dry_run: bool) -> Self {
        self.tx(|x| Tx { dry_run, ..x })
    }
    /// Simulate applying both the wrapper and inner transactions
    fn dry_run_wrapper(self, dry_run_wrapper: bool) -> Self {
        self.tx(|x| Tx {
            dry_run_wrapper,
            ..x
        })
    }
    /// Dump the transaction bytes to file
    fn dump_tx(self, dump_tx: bool) -> Self {
        self.tx(|x| Tx { dump_tx, ..x })
    }
    /// The output directory path to where serialize the data
    fn output_folder(self, output_folder: PathBuf) -> Self {
        self.tx(|x| Tx {
            output_folder: Some(output_folder),
            ..x
        })
    }
    /// Submit the transaction even if it doesn't pass client checks
    fn force(self, force: bool) -> Self {
        self.tx(|x| Tx { force, ..x })
    }
    /// Do not wait for the transaction to be added to the blockchain
    fn broadcast_only(self, broadcast_only: bool) -> Self {
        self.tx(|x| Tx {
            broadcast_only,
            ..x
        })
    }
    /// The address of the ledger node as host:port
    fn ledger_address(self, ledger_address: C::TendermintAddress) -> Self {
        self.tx(|x| Tx {
            ledger_address: C::ConfigRpcTendermintAddress::from(ledger_address),
            ..x
        })
    }
    /// If any new account is initialized by the tx, use the given alias to
    /// save it in the wallet.
    fn initialized_account_alias(
        self,
        initialized_account_alias: String,
    ) -> Self {
        self.tx(|x| Tx {
            initialized_account_alias: Some(initialized_account_alias),
            ..x
        })
    }
    /// Whether to force overwrite the above alias, if it is provided, in the
    /// wallet.
    fn wallet_alias_force(self, wallet_alias_force: bool) -> Self {
        self.tx(|x| Tx {
            wallet_alias_force,
            ..x
        })
    }
    /// The amount being paid (for gas unit) to include the transaction
    fn fee_amount(self, fee_amount: InputAmount) -> Self {
        self.tx(|x| Tx {
            fee_amount: Some(fee_amount),
            ..x
        })
    }
    /// The fee payer signing key
    fn wrapper_fee_payer(self, wrapper_fee_payer: C::PublicKey) -> Self {
        self.tx(|x| Tx {
            wrapper_fee_payer: Some(wrapper_fee_payer),
            ..x
        })
    }
    /// The token in which the fee is being paid
    fn fee_token(self, fee_token: C::Address) -> Self {
        self.tx(|x| Tx {
            fee_token: fee_token.into(),
            ..x
        })
    }
    /// The max amount of gas used to process tx
    fn gas_limit(self, gas_limit: GasLimit) -> Self {
        self.tx(|x| Tx { gas_limit, ..x })
    }
    /// The optional expiration of the transaction
    fn expiration(self, expiration: TxExpiration) -> Self {
        self.tx(|x| Tx { expiration, ..x })
    }
    /// The chain id for which the transaction is intended
    fn chain_id(self, chain_id: ChainId) -> Self {
        self.tx(|x| Tx {
            chain_id: Some(chain_id),
            ..x
        })
    }
    /// Sign the tx with the key for the given alias from your wallet
    fn signing_keys(self, signing_keys: Vec<C::PublicKey>) -> Self {
        self.tx(|x| Tx { signing_keys, ..x })
    }
    /// Path to the TX WASM code file to reveal PK
    fn tx_reveal_code_path(self, tx_reveal_code_path: PathBuf) -> Self {
        self.tx(|x| Tx {
            tx_reveal_code_path,
            ..x
        })
    }
    /// Password to decrypt key
    fn password(self, password: Zeroizing<String>) -> Self {
        self.tx(|x| Tx {
            password: Some(password),
            ..x
        })
    }
    /// Change memo
    fn memo(self, memo: Vec<u8>) -> Self {
        self.tx(|x| Tx {
            memo: Some(memo),
            ..x
        })
    }
}

impl<C: NamadaTypes> TxBuilder<C> for Tx<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        func(self)
    }
}

/// Wallet generate key and implicit address arguments
#[derive(Clone, Debug)]
pub struct KeyGen {
    /// Scheme type
    pub scheme: SchemeType,
    /// Whether to generate a spending key for the shielded pool
    pub shielded: bool,
    /// Whether to generate a raw non-hd key
    pub raw: bool,
    /// Key alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
    /// BIP44 / ZIP32 derivation path
    pub derivation_path: String,
    /// Prompt for BIP39 passphrase
    pub prompt_bip39_passphrase: bool,
    /// Allow non-compliant derivation path
    pub allow_non_compliant: bool,
    /// Optional block height after which this key was created.
    /// Only used for MASP keys.
    pub birthday: Option<BlockHeight>,
}

/// Wallet restore key and implicit address arguments
#[derive(Clone, Debug)]
pub struct KeyDerive {
    /// Scheme type
    pub scheme: SchemeType,
    /// Whether to generate a MASP spending key
    pub shielded: bool,
    /// Key alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
    /// Use the deprecated pure ZIP 32 algorithm
    pub unsafe_pure_zip32: bool,
    /// BIP44 / ZIP32 derivation path
    pub derivation_path: String,
    /// Allow non-compliant derivation path
    pub allow_non_compliant: bool,
    /// Prompt for BIP39 passphrase
    pub prompt_bip39_passphrase: bool,
    /// Use device to generate key and address
    pub use_device: bool,
    /// Hardware Wallet transport - HID (USB) or TCP
    pub device_transport: DeviceTransport,
    /// Optional blockheight after which this key was created.
    /// Only used for MASP keys
    pub birthday: Option<BlockHeight>,
}

/// Wallet list arguments
#[derive(Clone, Copy, Debug)]
pub struct KeyAddressList {
    /// Whether to list transparent secret keys only
    pub transparent_only: bool,
    /// Whether to list MASP spending keys only
    pub shielded_only: bool,
    /// List keys only
    pub keys_only: bool,
    /// List addresses only
    pub addresses_only: bool,
    /// Whether to decrypt secret / spending keys
    pub decrypt: bool,
    /// Show secret keys to user
    pub unsafe_show_secret: bool,
}

/// Wallet key / address lookup arguments
#[derive(Clone, Debug)]
pub struct KeyAddressFind {
    /// Alias to find
    pub alias: Option<String>,
    /// Address to find
    pub address: Option<Address>,
    /// Public key to lookup keypair with
    pub public_key: Option<common::PublicKey>,
    /// Public key hash to lookup keypair with
    pub public_key_hash: Option<String>,
    /// Payment address to find
    pub payment_address: Option<PaymentAddress>,
    /// Find keys only
    pub keys_only: bool,
    /// Find addresses only
    pub addresses_only: bool,
    /// Whether to decrypt secret / spending keys
    pub decrypt: bool,
    /// Show secret keys to user
    pub unsafe_show_secret: bool,
}
/// Wallet key export arguments
#[derive(Clone, Debug)]
pub struct KeyExport {
    /// Key alias
    pub alias: String,
}

/// Wallet key export arguments
#[derive(Clone, Debug)]
pub struct KeyConvert {
    /// Key alias
    pub alias: String,
}

/// Wallet key import arguments
#[derive(Clone, Debug)]
pub struct KeyImport {
    /// File name
    pub file_path: String,
    /// Key alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Don't encrypt the key
    pub unsafe_dont_encrypt: bool,
}

/// Wallet key / address add arguments
#[derive(Clone, Debug)]
pub struct KeyAddressAdd {
    /// Address alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Any supported value
    pub value: String,
    /// Optional block height after which this key was created.
    /// Only used for MASP keys.
    pub birthday: Option<BlockHeight>,
    /// Don't encrypt the key
    pub unsafe_dont_encrypt: bool,
}

/// Wallet key / address remove arguments
#[derive(Clone, Debug)]
pub struct KeyAddressRemove {
    /// Address alias
    pub alias: String,
    /// Confirmation to remove the alias
    pub do_it: bool,
}

/// Generate payment address arguments
#[derive(Clone, Debug)]
pub struct PayAddressGen {
    /// Payment address alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Viewing key
    pub viewing_key: String,
    /// Diversifier index to start search at
    pub diversifier_index: Option<DiversifierIndex>,
}

/// Bridge pool batch recommendation.
#[derive(Clone, Debug)]
pub struct RecommendBatch<C: NamadaTypes = SdkTypes> {
    /// The query parameters.
    pub query: Query<C>,
    /// The maximum amount of gas to spend.
    pub max_gas: Option<u64>,
    /// An optional parameter indicating how much net
    /// gas the relayer is willing to pay.
    pub gas: Option<u64>,
    /// Bridge pool recommendations conversion rates table.
    pub conversion_table: C::BpConversionTable,
}

/// A transfer to be added to the Ethereum bridge pool.
#[derive(Clone, Debug)]
pub struct EthereumBridgePool<C: NamadaTypes = SdkTypes> {
    /// Whether the transfer is for a NUT.
    ///
    /// By default, we add wrapped ERC20s onto the
    /// Bridge pool.
    pub nut: bool,
    /// The args for building a tx to the bridge pool
    pub tx: Tx<C>,
    /// The type of token
    pub asset: EthAddress,
    /// The recipient address
    pub recipient: EthAddress,
    /// The sender of the transfer
    pub sender: C::Address,
    /// The amount to be transferred
    pub amount: InputAmount,
    /// The amount of gas fees
    pub fee_amount: InputAmount,
    /// The account of fee payer.
    ///
    /// If unset, it is the same as the sender.
    pub fee_payer: Option<C::Address>,
    /// The token in which the gas is being paid
    pub fee_token: C::AddrOrNativeToken,
    /// Path to the tx WASM code file
    pub code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for EthereumBridgePool<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        EthereumBridgePool {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> EthereumBridgePool<C> {
    /// Whether the transfer is for a NUT.
    ///
    /// By default, we add wrapped ERC20s onto the
    /// Bridge pool.
    pub fn nut(self, nut: bool) -> Self {
        Self { nut, ..self }
    }

    /// The type of token
    pub fn asset(self, asset: EthAddress) -> Self {
        Self { asset, ..self }
    }

    /// The recipient address
    pub fn recipient(self, recipient: EthAddress) -> Self {
        Self { recipient, ..self }
    }

    /// The sender of the transfer
    pub fn sender(self, sender: C::Address) -> Self {
        Self { sender, ..self }
    }

    /// The amount to be transferred
    pub fn amount(self, amount: InputAmount) -> Self {
        Self { amount, ..self }
    }

    /// The amount of gas fees
    pub fn fee_amount(self, fee_amount: InputAmount) -> Self {
        Self { fee_amount, ..self }
    }

    /// The account of fee payer.
    ///
    /// If unset, it is the same as the sender.
    pub fn fee_payer(self, fee_payer: C::Address) -> Self {
        Self {
            fee_payer: Some(fee_payer),
            ..self
        }
    }

    /// The token in which the gas is being paid
    pub fn fee_token(self, fee_token: C::Address) -> Self {
        Self {
            fee_token: fee_token.into(),
            ..self
        }
    }

    /// Path to the tx WASM code file
    pub fn code_path(self, code_path: PathBuf) -> Self {
        Self { code_path, ..self }
    }
}

impl EthereumBridgePool {
    /// Build a transaction from this builder
    pub async fn build(
        self,
        context: &impl Namada,
    ) -> crate::error::Result<(namada_tx::Tx, SigningTxData)> {
        bridge_pool::build_bridge_pool_tx(context, self).await
    }
}

/// Bridge pool proof arguments.
#[derive(Debug, Clone)]
pub struct BridgePoolProof<C: NamadaTypes = SdkTypes> {
    /// The address of the ledger node as host:port
    pub ledger_address: C::TendermintAddress,
    /// The keccak hashes of transfers to
    /// acquire a proof of.
    pub transfers: Vec<KeccakHash>,
    /// The address of the node responsible for relaying
    /// the transfers.
    ///
    /// This node will receive the gas fees escrowed in
    /// the Bridge pool, to compensate the Ethereum relay
    /// procedure.
    pub relayer: Address,
}

/// Arguments to an Ethereum Bridge pool relay operation.
#[derive(Debug, Clone)]
pub struct RelayBridgePoolProof<C: NamadaTypes = SdkTypes> {
    /// The address of the ledger node as host:port
    pub ledger_address: C::TendermintAddress,
    /// The hashes of the transfers to be relayed
    pub transfers: Vec<KeccakHash>,
    /// The Namada address for receiving fees for relaying
    pub relayer: Address,
    /// The number of confirmations to wait for on Ethereum
    pub confirmations: u64,
    /// The Ethereum RPC endpoint.
    pub eth_rpc_endpoint: C::EthereumAddress,
    /// The Ethereum gas that can be spent during
    /// the relay call.
    pub gas: Option<u64>,
    /// The price of Ethereum gas, during the
    /// relay call.
    pub gas_price: Option<u64>,
    /// The address of the Ethereum wallet to pay the gas fees.
    /// If unset, the default wallet is used.
    pub eth_addr: Option<EthAddress>,
    /// Synchronize with the network, or exit immediately,
    /// if the Ethereum node has fallen behind.
    pub sync: bool,
}

/// Bridge validator set arguments.
#[derive(Debug, Clone)]
pub struct BridgeValidatorSet<C: NamadaTypes = SdkTypes> {
    /// The address of the ledger node as host:port
    pub ledger_address: C::TendermintAddress,
    /// The epoch to query.
    pub epoch: Option<Epoch>,
}

/// Governance validator set arguments.
#[derive(Debug, Clone)]
pub struct GovernanceValidatorSet<C: NamadaTypes = SdkTypes> {
    /// The address of the ledger node as host:port
    pub ledger_address: C::TendermintAddress,
    /// The epoch to query.
    pub epoch: Option<Epoch>,
}

/// Validator set proof arguments.
#[derive(Debug, Clone)]
pub struct ValidatorSetProof<C: NamadaTypes = SdkTypes> {
    /// The address of the ledger node as host:port
    pub ledger_address: C::TendermintAddress,
    /// The epoch to query.
    pub epoch: Option<Epoch>,
}

/// Validator set update relayer arguments.
#[derive(Debug, Clone)]
pub struct ValidatorSetUpdateRelay<C: NamadaTypes = SdkTypes> {
    /// Run in daemon mode, which will continuously
    /// perform validator set updates.
    pub daemon: bool,
    /// The address of the ledger node as host:port
    pub ledger_address: C::TendermintAddress,
    /// The number of block confirmations on Ethereum.
    pub confirmations: u64,
    /// The Ethereum RPC endpoint.
    pub eth_rpc_endpoint: C::EthereumAddress,
    /// The epoch of the validator set to relay.
    pub epoch: Option<Epoch>,
    /// The Ethereum gas that can be spent during
    /// the relay call.
    pub gas: Option<u64>,
    /// The price of Ethereum gas, during the
    /// relay call.
    pub gas_price: Option<u64>,
    /// The address of the Ethereum wallet to pay the gas fees.
    /// If unset, the default wallet is used.
    pub eth_addr: Option<EthAddress>,
    /// Synchronize with the network, or exit immediately,
    /// if the Ethereum node has fallen behind.
    pub sync: bool,
    /// The amount of time to sleep between failed
    /// daemon mode relays.
    pub retry_dur: Option<StdDuration>,
    /// The amount of time to sleep between successful
    /// daemon mode relays.
    pub success_dur: Option<StdDuration>,
}

/// IBC shielding transfer generation arguments
#[derive(Clone, Debug)]
pub struct GenIbcShieldingTransfer<C: NamadaTypes = SdkTypes> {
    /// The query parameters.
    pub query: Query<C>,
    /// The output directory path to where serialize the data
    pub output_folder: Option<PathBuf>,
    /// The target address
    pub target: C::TransferTarget,
    /// Transferred token amount
    pub amount: InputAmount,
    /// The optional expiration of the masp shielding transaction
    pub expiration: TxExpiration,
    /// Asset to shield over IBC to Namada
    pub asset: IbcShieldingTransferAsset<C>,
    /// The optional data for the frontend sustainability fee (the target and
    /// the amount, the token must be the same as the one involved in the
    /// shielding transaction since ics-20 only supports a single asset)
    /// NOTE: if the shielding operation is part of a swap, and this is
    /// shielded (from MASP to MASP), no sustainability fee should be taken
    // FIXME: transparent target only
    pub frontend_sus_fee: Option<(C::TransferTarget, InputAmount)>,
}

/// IBC shielding transfer asset, to be used by [`GenIbcShieldingTransfer`]
#[derive(Clone, Debug)]
pub enum IbcShieldingTransferAsset<C: NamadaTypes = SdkTypes> {
    /// Attempt to look-up the address of the asset to shield on Namada
    LookupNamadaAddress {
        /// The token address which could be a non-namada address
        token: String,
        /// Port ID via which the token is received
        port_id: PortId,
        /// Channel ID via which the token is received
        channel_id: ChannelId,
    },
    /// Namada address of the token that will be received.
    Address(C::Address),
}
